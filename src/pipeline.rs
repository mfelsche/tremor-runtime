// Copyright 2018-2020, Wayfair GmbH
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
use crate::errors::{Error, Result};
use crate::registry::ServantId;
use crate::repository::PipelineArtefact;
use crate::url::TremorURL;
use crate::utils::nanotime;
use crate::{offramp, onramp};
use async_std::sync::channel;
use async_std::task::{self, JoinHandle};
use crossbeam_channel::{bounded, Sender as CbSender};
use simd_json::prelude::*;
use simd_json::BorrowedValue;
use std::borrow::Cow;
use std::time::Duration;
use std::{fmt, thread};
use tremor_pipeline::{Event, ExecutableGraph, SignalKind};

const TICK_MS: u64 = 1000;
pub(crate) type Sender = async_std::sync::Sender<ManagerMsg>;

/// Address for a a pipeline
#[derive(Clone)]
pub struct Addr {
    pub(crate) addr: CbSender<Msg>,
    pub(crate) id: ServantId,
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pipeline({})", self.id)
    }
}

#[derive(Debug)]
pub(crate) enum Msg {
    Event {
        event: Event,
        input: Cow<'static, str>,
    },
    ConnectOfframp(Cow<'static, str>, TremorURL, offramp::Addr),
    ConnectOnramp(TremorURL, onramp::Addr),
    ConnectPipeline(Cow<'static, str>, TremorURL, Addr),
    DisconnectOutput(Cow<'static, str>, TremorURL),
    DisconnectInput(TremorURL),
    #[allow(dead_code)]
    Signal(Event),
    Insight(Event),
}

#[derive(Debug)]
pub enum Dest {
    Offramp(offramp::Addr),
    Pipeline(Addr),
}
impl Dest {
    pub fn send_event(&self, input: Cow<'static, str>, event: Event) -> Result<()> {
        match self {
            Self::Offramp(addr) => addr.send(offramp::Msg::Event { input, event })?,
            Self::Pipeline(addr) => addr.addr.send(Msg::Event { input, event })?,
        }
        Ok(())
    }
    pub fn send_signal(&self, signal: Event) -> Result<()> {
        match self {
            Self::Offramp(addr) => addr.send(offramp::Msg::Signal(signal))?,
            Self::Pipeline(addr) => {
                // Each pipeline has their own ticks, we don't
                // want to propagate them
                if signal.kind != Some(SignalKind::Tick) {
                    addr.addr.send(Msg::Signal(signal))?
                }
            }
        }
        Ok(())
    }
}

pub struct Create {
    pub config: PipelineArtefact,
    pub id: ServantId,
}

pub(crate) enum ManagerMsg {
    Stop,
    Create(async_std::sync::Sender<Result<Addr>>, Create),
}

#[derive(Default, Debug)]
pub(crate) struct Manager {
    qsize: usize,
}

#[inline]
fn send_events(
    eventset: &mut Vec<(Cow<'static, str>, Event)>,
    dests: &halfbrown::HashMap<Cow<'static, str>, Vec<(TremorURL, Dest)>>,
) -> Result<()> {
    for (output, event) in eventset.drain(..) {
        if let Some(dest) = dests.get(&output) {
            let len = dest.len();
            //We know we have len, so grabbing len - 1 elementsis safe
            for (id, offramp) in unsafe { dest.get_unchecked(..len - 1) } {
                offramp.send_event(
                    id.instance_port()
                        .ok_or_else(|| Error::from(format!("missing instance port in {}.", id)))?
                        .to_string()
                        .into(),
                    event.clone(),
                )?;
            }
            //We know we have len, so grabbing the last elementsis safe
            let (id, offramp) = unsafe { dest.get_unchecked(len - 1) };
            offramp.send_event(
                id.instance_port()
                    .ok_or_else(|| Error::from(format!("missing instance port in {}.", id)))?
                    .to_string()
                    .into(),
                event,
            )?;
        };
    }
    Ok(())
}

#[inline]
fn send_signal(
    own_id: &TremorURL,
    signal: Event,
    dests: &halfbrown::HashMap<Cow<'static, str>, Vec<(TremorURL, Dest)>>,
) -> Result<()> {
    let mut offramps = dests.values().flatten();
    let first = offramps.next();
    for (id, offramp) in offramps {
        if id != own_id {
            offramp.send_signal(signal.clone())?;
        }
    }
    if let Some((id, offramp)) = first {
        if id != own_id {
            offramp.send_signal(signal)?;
        }
    }
    Ok(())
}

#[inline]
async fn handle_insight(
    insight: Event,
    pipeline: &mut ExecutableGraph,
    onramps: &halfbrown::HashMap<TremorURL, onramp::Addr>,
) {
    let insight = pipeline.contraflow(insight);
    let (_e, m) = insight.data.parts();
    if dbg!(&m)
        .get("trigger")
        .and_then(ValueTrait::as_bool)
        .unwrap_or_default()
    {
        dbg!("trigger");
        for (_k, o) in onramps {
            o.send(onramp::Msg::Trigger).await
        }
    //this is a trigger event
    } else if dbg!(&m)
        .get("restore")
        .and_then(ValueTrait::as_bool)
        .unwrap_or_default()
    {
        dbg!("restore");
        for (_k, o) in onramps {
            o.send(onramp::Msg::Restore).await
        }

        //this is a trigger event
    }
}

impl Manager {
    pub fn new(qsize: usize) -> Self {
        Self { qsize }
    }
    pub fn start(self) -> (JoinHandle<bool>, Sender) {
        let (tx, rx) = channel(64);
        let h = task::spawn(async move {
            info!("Pipeline manager started");
            loop {
                match rx.recv().await {
                    Ok(ManagerMsg::Stop) => {
                        info!("Stopping onramps...");
                        break;
                    }
                    Ok(ManagerMsg::Create(r, create)) => r.send(self.start_pipeline(create)).await,
                    Err(e) => {
                        info!("Stopping onramps... {}", e);
                        break;
                    }
                }
            }
            info!("Pipeline manager stopped");
            true
        });
        (h, tx)
    }

    #[allow(clippy::too_many_lines)]
    fn start_pipeline(&self, req: Create) -> Result<Addr> {
        let config = req.config;
        let id = req.id.clone();
        let mut dests: halfbrown::HashMap<Cow<'static, str>, Vec<(TremorURL, Dest)>> =
            halfbrown::HashMap::new();
        let mut onramps: halfbrown::HashMap<TremorURL, onramp::Addr> = halfbrown::HashMap::new();
        let mut eventset: Vec<(Cow<'static, str>, Event)> = Vec::new();
        let (tx, rx) = bounded::<Msg>(self.qsize);
        let mut pipeline = config.to_executable_graph(tremor_pipeline::buildin_ops)?;
        let mut pid = req.id.clone();
        pid.trim_to_instance();
        pipeline.id = pid.to_string();
        let tick_tx = tx.clone();
        task::spawn(async move {
            let mut e = Event {
                is_batch: false,
                id: 0,
                data: (BorrowedValue::null(), BorrowedValue::object()).into(),
                ingest_ns: nanotime(),
                origin_uri: None,
                kind: Some(SignalKind::Tick),
            };
            while tick_tx.send(Msg::Signal(e.clone())).is_ok() {
                task::sleep(Duration::from_millis(TICK_MS)).await;
                e.ingest_ns = nanotime()
            }
        });
        thread::Builder::new()
            .name(format!("pipeline-{}", id.clone()))
            .spawn(move || {
                info!("[Pipeline:{}] starting thread.", id);
                for req in rx {
                    match req {
                        Msg::Event { input, event } => {
                            match pipeline.enqueue(&input, event, &mut eventset) {
                                Ok(()) => {
                                    if let Err(e) = send_events(&mut eventset, &dests) {
                                        error!("Failed to send event: {}", e)
                                    }
                                }
                                Err(e) => error!("error: {:?}", e),
                            }
                        }
                        Msg::Insight(insight) => {
                            task::block_on(handle_insight(insight, &mut pipeline, &onramps))
                        }
                        Msg::Signal(signal) => match pipeline
                            .enqueue_signal(signal.clone(), &mut eventset)
                        {
                            Ok(insights) => {
                                if let Err(e) = send_signal(&id, signal, &dests) {
                                    error!("Failed to send signal: {}", e)
                                }

                                for insight in insights {
                                    task::block_on(handle_insight(insight, &mut pipeline, &onramps))
                                }

                                if let Err(e) = send_events(&mut eventset, &dests) {
                                    error!("Failed to send event: {}", e)
                                }
                            }
                            Err(e) => error!("error: {:?}", e),
                        },
                        Msg::ConnectOfframp(output, offramp_id, offramp) => {
                            info!(
                                "[Pipeline:{}] connecting {} to offramp {}",
                                id, output, offramp_id
                            );
                            if let Some(offramps) = dests.get_mut(&output) {
                                offramps.push((offramp_id, Dest::Offramp(offramp)));
                            } else {
                                dests.insert(output, vec![(offramp_id, Dest::Offramp(offramp))]);
                            }
                        }
                        Msg::ConnectPipeline(output, pipeline_id, pipeline) => {
                            info!(
                                "[Pipeline:{}] connecting {} to pipeline {}",
                                id, output, pipeline_id
                            );
                            if let Some(offramps) = dests.get_mut(&output) {
                                offramps.push((pipeline_id, Dest::Pipeline(pipeline)));
                            } else {
                                dests.insert(output, vec![(pipeline_id, Dest::Pipeline(pipeline))]);
                            }
                        }
                        Msg::ConnectOnramp(onramp_id, onramp) => {
                            println!("connecting onramp: {}", onramp_id);
                            onramps.insert(onramp_id, onramp);
                        }
                        Msg::DisconnectOutput(output, to_delete) => {
                            let mut remove = false;
                            if let Some(offramp_vec) = dests.get_mut(&output) {
                                offramp_vec.retain(|(this_id, _)| this_id != &to_delete);
                                remove = offramp_vec.is_empty();
                            }
                            if remove {
                                dests.remove(&output);
                            }
                        }
                        Msg::DisconnectInput(onramp_id) => {
                            println!("disconnecting onramp: {}", onramp_id);
                            onramps.remove(&onramp_id);
                        }
                    };
                }
                info!("[Pipeline:{}] stopping thread.", id);
            })?;
        Ok(Addr {
            id: req.id,
            addr: tx,
        })
    }
}
