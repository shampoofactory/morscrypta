use std::io;
use std::io::Read;

pub trait ReadFully {
    fn read_fully(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

impl<R: Read> ReadFully for R {
    fn read_fully(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut idx = 0;
        let mut is_eof = false;
        while idx != buf.len() && !is_eof {
            let n = self.read(&mut buf[idx..])?;
            is_eof = n == 0;
            idx += n;
        }
        Ok(idx)
    }
}
