// Copyright 2018-2019, Wayfair GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::codec::Codec;
use crate::errors::*;
use crate::registry::ServantId;
use crate::system::PipelineAddr;
use crate::system::Stop;
use crate::url::TremorURL;
use crate::{Event, OpConfig};
use actix::prelude::*;
use crossbeam_channel::{bounded, Sender};
use std::fmt;
use std::thread;

mod blackhole;
mod debug;
mod elastic;
mod file;
mod gcs;
mod gpub;
mod kafka;
mod prelude;
mod rest;
mod stderr;
mod stdout;
mod tcp;
mod udp;

pub enum OfframpMsg {
    Event { event: Event, input: String },
    Connect { id: TremorURL, addr: PipelineAddr },
    Disconnect { id: TremorURL, tx: Sender<bool> },
}

pub type OfframpAddr = Sender<OfframpMsg>;

// We allow this here since we can't pass in &dyn Code as that would taint the
// overlying object with lifetimes.
// We also can't pass in Box<dyn Codec> as that would try to move it out of
// borrowed contest
#[allow(clippy::borrowed_box)]
pub trait Offramp: Send {
    fn start(&mut self, codec: &Box<dyn Codec>, postprocessors: &[String]);
    fn on_event(&mut self, codec: &Box<dyn Codec>, input: String, event: Event);
    fn default_codec(&self) -> &str;
    fn add_pipeline(&mut self, _id: TremorURL, _addr: PipelineAddr);
    fn remove_pipeline(&mut self, _id: TremorURL) -> bool;
}

trait OfframpImpl {
    fn from_config(config: &Option<OpConfig>) -> Result<Box<dyn Offramp>>;
}

pub fn lookup(name: String, config: Option<OpConfig>) -> Result<Box<dyn Offramp>> {
    match name.as_str() {
        "blackhole" => blackhole::Blackhole::from_config(&config),
        "debug" => debug::Debug::from_config(&config),
        "elastic" => elastic::Elastic::from_config(&config),
        "file" => file::File::from_config(&config),
        "gcs" => gcs::GCS::from_config(&config),
        "gpub" => gpub::GPub::from_config(&config),
        "kafka" => kafka::Kafka::from_config(&config),
        "rest" => rest::Rest::from_config(&config),
        "stdout" => stdout::StdOut::from_config(&config),
        "stderr" => stderr::StdErr::from_config(&config),
        "tcp" => tcp::Tcp::from_config(&config),
        "udp" => udp::Udp::from_config(&config),
        _ => Err(format!("Offramp {} not known", name).into()),
    }
}

#[derive(Debug, Default)]
pub struct Manager {
    pub qsize: usize,
}

impl Actor for Manager {
    type Context = Context<Self>;
    fn started(&mut self, _ctx: &mut Context<Self>) {
        info!("Offramp manager started");
    }
}

pub struct CreateOfframp {
    pub id: ServantId,
    pub offramp: Box<dyn Offramp>,
    pub codec: Box<dyn Codec>,
    pub postprocessors: Vec<String>,
}

impl fmt::Debug for CreateOfframp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "StartOfframp({})", self.id)
    }
}

impl Message for CreateOfframp {
    type Result = Result<OfframpAddr>;
}

impl Handler<CreateOfframp> for Manager {
    type Result = Result<OfframpAddr>;
    fn handle(&mut self, mut req: CreateOfframp, _ctx: &mut Context<Self>) -> Self::Result {
        req.offramp.start(&req.codec, &req.postprocessors);

        let (tx, rx) = bounded(self.qsize);
        let offramp_id = req.id.clone();
        // let mut s = req;
        thread::spawn(move || {
            info!("[Offramp::{}] started", offramp_id);
            for m in rx {
                match m {
                    OfframpMsg::Event { event, input } => {
                        // TODO FIXME implement postprocessors
                        req.offramp.on_event(&req.codec, input, event);
                    }
                    OfframpMsg::Connect { id, addr } => {
                        info!("[Offramp::{}] Connecting pipeline {}", offramp_id, id);
                        req.offramp.add_pipeline(id, addr);
                    }
                    OfframpMsg::Disconnect { id, tx } => {
                        info!("[Offramp::{}] Disconnecting pipeline {}", offramp_id, id);
                        let r = req.offramp.remove_pipeline(id.clone());
                        info!("[Offramp::{}] Pipeline {} disconnected", offramp_id, id);
                        if r {
                            info!("[Offramp::{}] Marked as done ", offramp_id);
                        }
                        let _ = tx.send(r);
                    }
                }
            }
            info!("[Offramp::{}] stopped", offramp_id);
        });
        Ok(tx)
    }
}

impl Handler<Stop> for Manager {
    type Result = ();
    fn handle(&mut self, _req: Stop, _ctx: &mut Self::Context) -> Self::Result {
        // TODO: Propper shutdown needed?
        info!("Stopping offramps");
        System::current().stop();
    }
}