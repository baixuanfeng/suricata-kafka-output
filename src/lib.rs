// Copyright (c) 2021 Open Information Security Foundation
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

// FFI helpers. This will be removed when these helpers get added to the
// Suricata rust code (where they belong).
mod ffi;

use rdkafka::error::{KafkaError};
use rdkafka::{ClientConfig};
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::fmt::Error;
use std::os::raw::{c_char, c_int, c_void};
//use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
//use std::sync::Arc;
use suricata::conf::ConfNode;
use suricata::{SCLogError, SCLogNotice};

// Default configuration values. Kafka requires a broker list and topic, so
const DEFAULT_BUFFER_SIZE: &str = "65535";
const DEFAULT_CLIENT_ID: &str = "rdkafka";
const DEFAULT_

#[derive(Debug, Clone)]     
struct ProducerConfig {
    brokers: String,
    topic: String,
    client_id: String,
    buffer: usize,
}

impl ProducerConfig {
    fn new(conf: &ConfNode) -> Result<Self,Error> {
        let brokers = if let Some(val) = conf.get_child_value("brokers"){
            val.to_string()
        }else {
            SCLogError!("brokers parameter required!");
            panic!();
        };
        let topic = if let Some(val) = conf.get_child_value("topic"){
            val.to_string()
        }else {
            SCLogError!("topic parameter required!");
            panic!();
        };
        let client_id = conf.get_child_value("client-id").unwrap_or(DEFAULT_CLIENT_ID);
        let buffer_size = match conf
            .get_child_value("buffer-size")
            .unwrap_or(DEFAULT_BUFFER_SIZE)
            .parse::<usize>()
        {
            Ok(size) => size,
            Err(_) => {
                SCLogError!("invalid buffer-size!");
                panic!();
            },
        };
        let config = ProducerConfig {
            brokers: brokers.into(),
            topic: topic.into(),
            client_id: client_id.into(),
            buffer: buffer_size,
        };
        Ok(config)
    }
}


struct KafkaProducer {
    producer: FutureProducer,
    config: ProducerConfig,
    rx: std::sync::mpsc::Receiver<String>,
    count: usize,
}



impl KafkaProducer {
    fn new(
        config: ProducerConfig,
        rx: std::sync::mpsc::Receiver<String>,
    ) -> Result<Self,KafkaError> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", &config.brokers)
            .set("client.id",&config.client_id)
            .set("message.timeout.ms", "5000")
            .create()?;
        Ok(Self {
            config,
            producer,
            rx,
            count: 0,
        })
    }


    fn run(&mut self) {
        // Get a peekable iterator from the incoming channel. This allows us to
        // get the next message from the channel without removing it, we can
        // then remove it once its been sent to the server without error.
        //
        // Not sure how this will work with pipe-lining tho, will probably have
        // to do some buffering here, or just accept that any log records
        // in-flight will be lost.
        let mut iter = self.rx.iter().peekable();
            loop {
                if let Some(buf) = iter.peek() {
                    self.count += 1;
                    if let Err(err) = self.producer.send_result(
                        FutureRecord::to(&self.config.topic)
                            .key("")
                            .payload(&buf),
                    ) {
                        SCLogError!("Failed to send event to Kafka: {:?}", err);
                        break;
                    } else {
                        // Successfully sent.  Pop it off the channel.
                        let _ = iter.next();

                    }
                } else {
                    break;
                }
            }
            SCLogNotice!("Producer finished: count={}", self.count,);
    }
}

struct Context { 
    tx: SyncSender<String>,
    th: JoinHandle<()>,
    thread: Option<ThreadContext>,
    count: usize,
    dropped: usize,
}

struct ThreadContext {
    thread_id: usize,
    tx: SyncSender<String>,
    count: usize,
    dropped: usize,
}

impl ThreadContext {
    fn new(thread_id: usize, tx: SyncSender<String>) -> Self {
        Self {
            thread_id,
            tx,
            count: 0,
            dropped: 0,
        }
    }

    fn send(&mut self, buf: &str) {
        self.count += 1;
        if let Err(err) = self.tx.try_send(buf.to_string()) {
            self.dropped += 1;
            match err {
                TrySendError::Full(_) => {
                    SCLogError!("Eve record lost due to full buffer");
                }
                TrySendError::Disconnected(_) => {
                    SCLogError!("Eve record lost due to broken channel{}",err);
                }
            }
        }
    }

    fn log_exit_stats(&self) {
        SCLogNotice!(
            "Kafka output finished: thread={}, count={}, dropped={}",
            self.thread_id,
            self.count,
            self.dropped
        );
    }
}


unsafe extern "C" fn output_init(conf: *const c_void, threaded: bool, init_data: *mut *mut c_void) -> c_int {
    // Load configuration.
    // let config = ProducerConfig::new(&ConfNode::wrap(conf)).unwrap();
    let config = ConfNode::wrap(conf).get_child("kafka").map(|conf| ProducerConfig::new(&conf)).unwrap().unwrap();

    let (tx, rx) = std::sync::mpsc::sync_channel(config.buffer);

    let mut kafka_producer = match KafkaProducer::new(config, rx) {
        Ok(producer) => {
            SCLogNotice!(
                "KafKa Producer initialize success with brokers:{:?} | topic: {:?} | client_id: {:?} | buffer-size: {:?}", 
                producer.config.brokers,
                producer.config.topic,
                producer.config.client_id,
                producer.config.buffer
            );
            producer
        }
        Err(err) => {
            SCLogError!("Failed to initialize Kafka Producer: {:?}", err);
            panic!()
        }
    };

    let th = std::thread::spawn(move || {kafka_producer.run()});
    // kafka_producer.run();

    let context = Context {
        tx: tx.clone(),
        th, 
        thread: if threaded {
            None
        } else {
            Some(ThreadContext::new(1, tx))
        },
        count: 0,
        dropped: 0,
    };


    *init_data = Box::into_raw(Box::new(context)) as *mut _;
    0
}

unsafe extern "C" fn output_close(init_data: *const c_void) {
    let context = Box::from_raw(init_data as *mut Context);
    SCLogNotice!(
        "Kafka produce finished: count={}, dropped={}",
        context.count,
        context.dropped
    );
    std::mem::drop(context);
}

unsafe extern "C" fn output_write(
    buffer: *const c_char,
    buffer_len: c_int,
    init_data: *const c_void,
    thread_data: *const c_void,
) -> c_int {
    let context = &mut *(init_data as *mut Context);

    // If thread_data is null then we're setup for single threaded mode, and use
    // the default thread context.
    let thread_context = if thread_data.is_null() {
        context.thread.as_mut().unwrap()
    } else {
        &mut *(thread_data as *mut ThreadContext)
    };

    let buf = if let Ok(buf) = ffi::str_from_c_parts(buffer, buffer_len) {
        buf
    } else {
        return -1;
    };

    thread_context.send(buf);
    0
}

unsafe extern "C" fn output_thread_init(
    init_data: *const c_void,
    thread_id: std::os::raw::c_int,
    thread_data: *mut *mut c_void,
) -> c_int {
    let context = &mut *(init_data as *mut Context);
    let thread_context = ThreadContext::new(thread_id as usize, context.tx.clone());
    *thread_data = Box::into_raw(Box::new(thread_context)) as *mut _;
    0
}

unsafe extern "C" fn output_thread_deinit(_init_data: *const c_void, thread_data: *mut c_void) {
    let thread_context = Box::from_raw(thread_data as *mut ThreadContext);
    thread_context.log_exit_stats();
    std::mem::drop(thread_context);
}

unsafe extern "C" fn init_plugin() {
    let file_type =
        ffi::SCEveFileType::new("kafka", output_init, output_close, output_write, output_thread_init, output_thread_deinit);
    ffi::SCRegisterEveFileType(file_type);
}

#[no_mangle]
extern "C" fn SCPluginRegister() -> *const ffi::SCPlugin {
    // Rust plugins need to initialize some Suricata internals so stuff like logging works.
    suricata::plugin::init();

    // Register our plugin.
    ffi::SCPlugin::new("Kafka Eve Filetype", "GPL-2.0", "sven", init_plugin)
}
