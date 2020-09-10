
use super::prelude::*;
use simd_json::value::borrowed::{Object, Value};
use syslog_loose::{ProcId, SyslogFacility, SyslogSeverity};
use chrono::{DateTime, NaiveDateTime};


#[derive(Clone)]
pub struct Syslog {}
// whoa!
// Ich kann sogar kommentare schreiben; vscode live ist echt super fuer peer programming
// willkommen! hab leider keine kekse da gerade :(
impl Codec for Syslog {

    fn decode(&mut self, data: Vec<u8>, ingest_ns: u64) -> Result<Option<LineValue>> {
        LineValue::try_new(vec![data], |raw| {
            decode(&raw[0]).map(ValueAndMeta::from)
        })
        .map_err(|e| e.0)
        .map(Some)

    }

    fn encode(&self, data: &simd_json::BorrowedValue) -> Result<Vec<u8>> {
        encode(data)
    }
}

fn decode(data: &[u8]) -> Result<Value> {
    // TODO: parse directly to Values
    let msg = syslog_loose::parse_message(std::str::from_utf8(data)?);
    let mut v = Object::vec_with_capacity(9);
    if let Some(facility) = msg.facility {
        v.insert_nocheck("facility".into(), Value::from(facility as i32));
    }
    if let Some(severity) = msg.severity {
        v.insert_nocheck("severity".into(), Value::from(severity as i32));
    }
    if let Some(ts) = msg.timestamp {
        v.insert_nocheck("timestamp".into(), Value::from(ts.timestamp()));
        v.insert_nocheck("timestamp_rfc3339".into(), Value::from(ts.to_rfc3339()));
    }
    if let Some(hostname) = msg.hostname {
        v.insert_nocheck("hostname".into(), Value::from(hostname));
    }
    if let Some(app) = msg.appname {
        v.insert_nocheck("appname".into(), Value::from(app));
    }

    match msg.procid { // grmpf
        Some(ProcId::PID(pid)) =>
            v.insert_nocheck("procid".into(), Value::from(pid.to_string())),
        Some(ProcId::Name(strProcId)) =>
            v.insert_nocheck("procid".into(), Value::from(strProcId)),
        _ => (),
    }
    if let Some(msgid) = msg.msgid {
        v.insert_nocheck("msgid".into(), Value::from(msgid));
    }

    if !msg.structured_data.is_empty() {
        let sd_map = Object::vec_with_capacity(msg.structured_data.len());
        for sd in msg.structured_data {
            let sd_param_map = Object::with_capacity(sd.params.len());
            for (param_name, param_value) in sd.params {
                sd_param_map.insert(param_name.into(), param_value.into());
            }
            sd_map.insert(sd.id.into(), Value::from(sd_param_map));
        }
        v.insert_nocheck("structured_data".into(), Value::from(sd_map));
    }
    v.insert_nocheck("msg".into(), Value::from(msg.msg));

    Ok(Value::from(v))
}

/**
 * encode as RFC5424 syslog message
 */
fn encode(data: &Value) -> Result<Vec<u8>> {
    // Header:
    // PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
    //
    // HEADER SP STRUCTURED_DATA SP MSG
    let mut res: String = String::new();
    let pri = match (data.get("facility").and_then(|f| f.as_i32()), data.get("severity").and_then(|s| s.as_i32())) {
        (Some(facility), Some(severity)) => (facility << 3) + severity,
        _ => 13i32
    }
    res.push('<');
    res.push_str(pri.to_string().as_str());
    res.push_str(">1 ");
    res.push_str(data.get("timestamp_rfc3339").and_then(|ts| ts.as_str()).unwrap_or("-"));
    res.push(' ');
    res.push_str(data.get("hostname").and_then(|hn| hn.as_str()).unwrap_or("-"));
    res.push(' ');
    res.push_str(data.get("appname").and_then(|an| an.as_str()).unwrap_or("-"));
    res.push(' ');
    res.push_str(data.get("procid").and_then(|pi| pi.as_str()).unwrap_or("-"));
    res.push(' ');
    res.push_str(data.get("msgid").and_then(|m| m.as_str()).unwrap_or("-"));
    res.push(' ');
    res.push_str(data.get("structured_data").and_then(|sd| sd.as_object()).map(|sd| {
        ""
    }).unwrap_or("-");



    
    Ok(res.as_bytes().to_vec())
}

#[cfg(test)]
mod test {
    use super::*;
    use simd_json::json;

    #[test]
    fn decode_rfc5424_format() -> Result<()> {
        let msg = b"<13>1 2020-09-01T20:50:59.984182+02:00 hostname mat 698596 - [timeQuality tzKnown=\"1\" isSynced=\"1\" syncAccuracy=\"3500\"] yeah";
        let decoded = decode(msg).expect("failed to decode");
        let expected: Value = json!({
            "facility": "user",
            "severity": "info",
            "timestamp": 123,
            "hostname": "matschenk",
            "app": "",
            "procid": "698596",
            "msgid": "",
            "msg": "yeah",

        });

        Ok(())
    }
}
