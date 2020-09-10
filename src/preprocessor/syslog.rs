use super::Preprocessor;
use crate::errors::Result;

#[derive(Clone)]
enum ParseState {
    ExpectFrameSize,
    ExpectBytes(usize)
}

#[derive(Clone)]
pub struct SyslogTLS {
    state: ParseState,
    frame_buffer: Vec<u8>
}


impl SyslogTLS {
    pub fn new() -> Self {
        Self {
            state: ParseState::ExpectFrameSize,
            frame_buffer: vec![]
        }
    }

    fn parse(&mut self, data: &[u8], acc: &mut Vec<Vec<u8>>) -> Result<()> {
        match self.state {
            ParseState::ExpectFrameSize => {
                // searching for a SP
                let mut source = data;
                loop {
                    if let Some(first_space_pos) = source.iter().position(|char| char == &b' ') {
                        // parse frame_size 
                        let mut size_str = String::with_capacity(self.frame_buffer.len() + first_space_pos);
                        size_str.push_str(std::str::from_utf8(self.frame_buffer.as_slice())?);
                        size_str.push_str(std::str::from_utf8(&source[..first_space_pos])?);
                        self.frame_buffer = vec![]; // fully consumed
                        let frame_size = size_str.parse::<usize>()?;

                        let frame_start = first_space_pos + 1;
                        let frame_end = frame_start + frame_size;
                        if (source.len() - frame_start) >= frame_size {
                            let frame = source[frame_start..frame_end].to_vec();
                            acc.push(frame);
                            source = &source[frame_end..];
                        } else {
                            // frame not complete yet
                            self.frame_buffer = data[(first_space_pos + 1)..].to_vec();
                            self.state = ParseState::ExpectBytes(frame_size - self.frame_buffer.len());
                            break;
                        }
                    } else {
                        // no frame size yet
                        self.frame_buffer.extend_from_slice(source);
                        self.state = ParseState::ExpectFrameSize;
                        break;
                    }
                }
            },
            ParseState::ExpectBytes(bytes) =>
                if self.frame_buffer.len() + data.len() >= bytes {
                    let take_bytes = bytes - self.frame_buffer.len();
                    self.frame_buffer.extend_from_slice(&data[..take_bytes]);
                    acc.push(self.frame_buffer.clone());
                    self.frame_buffer.clear();
                    self.state = ParseState::ExpectFrameSize;
                    // recurse, woohoo!
                    self.parse(&data[take_bytes..], acc)?;
                } else {
                    // frame not complete yet, need to wait for next data chunk
                    self.frame_buffer.extend_from_slice(data);
                    self.state = ParseState::ExpectBytes(bytes - data.len());
                }
        }
        // TBD
        Ok(())
    }
}

impl Preprocessor for SyslogTLS {
    fn process(&mut self, _ingest_ns: &mut u64, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut res = Vec::with_capacity(2);
        self.parse(data, &mut res)?;
        Ok(res)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    //use proptest::prelude::*;

    #[test]
    fn handle_empty_data() {
        let mut ingest_ns = 0;
        let mut preprocessor = SyslogTLS::new();
        let data: Vec<u8> = vec![];
        let res = preprocessor.process(&mut ingest_ns, data.as_slice());
        assert_eq!(Ok(vec![]), res);
    }

    #[test]
    fn error_on_garbage_length() {
        let mut ingest_ns = 0;
        let mut preprocessor = SyslogTLS::new();
        let data: Vec<u8> = vec![b'a', b'b', b'c', b' '];
        let res = preprocessor.process(&mut ingest_ns, data.as_slice());
        assert!(res.is_err());
    }

}
