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

use super::Codec;
use crate::errors::*;
use simd_json;
use tremor_script::LineValue;

#[derive(Clone)]
pub struct JSON {}

impl Codec for JSON {
    fn decode(&mut self, data: Vec<u8>, _ingest_ns: u64) -> Result<Option<LineValue>> {
        LineValue::try_new(Box::new(data), |data| simd_json::to_borrowed_value(data))
            .map(Some)
            .map_err(|e| e.0.into())
    }
    fn encode(&self, data: LineValue) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        data.suffix().write(&mut v)?;
        Ok(v)
    }
}