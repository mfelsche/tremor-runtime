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

//! # Debug offramp reporting classification statistics.
//!
//! The debug offramp periodically reports on the number of events
//! per classification.
//!
//! ## Configuration
//!
//! This operator takes no configuration

use crate::offramp::prelude::*;
use crate::sink::{Event, OpConfig, Result, Sink, SinkManager};
use async_std::io;
use async_std::prelude::*;

pub struct StdOut {
    postprocessors: Postprocessors,
    stdout: io::Stdout,
}

impl offramp::Impl for StdOut {
    fn from_config(_config: &Option<OpConfig>) -> Result<Box<dyn Offramp>> {
        Ok(SinkManager::new_box(Self {
            postprocessors: vec![],
            stdout: io::stdout(),
        }))
    }
}
#[async_trait::async_trait]
impl Sink for StdOut {
    #[allow(unused_variables)]
    async fn on_event(&mut self, input: &str, codec: &dyn Codec, event: Event) -> ResultVec {
        for value in event.value_iter() {
            let raw = codec.encode(value)?;
            if let Ok(s) = std::str::from_utf8(&raw) {
                self.stdout.write_all(s.as_bytes()).await?
            } else {
                self.stdout
                    .write_all(format!("{:?}", raw).as_bytes())
                    .await?
            }
        }
        Ok(None)
    }
    async fn init(&mut self, postprocessors: &[String]) -> Result<()> {
        self.postprocessors = make_postprocessors(postprocessors)?;
        Ok(())
    }
    fn default_codec(&self) -> &str {
        "json"
    }
    #[allow(unused_variables)]
    async fn on_signal(&mut self, signal: Event) -> ResultVec {
        Ok(None)
    }
    fn is_active(&self) -> bool {
        true
    }
    fn auto_ack(&self) -> bool {
        true
    }
}
