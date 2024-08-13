use std::{borrow::Cow, iter::Flatten};

/// A vector that is split into chunks.
///
/// Used to get around WASM large allocation limits.
pub struct ChunkedVec<T>(Vec<Vec<T>>);

impl<T> ChunkedVec<T> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push_chunk(&mut self, chunk: Vec<T>) {
        self.0.push(chunk);
    }
}

impl<T> IntoIterator for ChunkedVec<T> {
    type Item = T;
    type IntoIter = Flatten<std::vec::IntoIter<Vec<T>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter().flatten()
    }
}

impl<T> ChunkedVec<T> {
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter().flatten()
    }
    pub fn iter_chunks(&self) -> impl Iterator<Item = &Vec<T>> {
        self.0.iter()
    }
}

struct FlatSplit<'a, T, I>
where
    T: PartialEq + Clone + 'a,
    I: Iterator<Item = &'a [T]>,
{
    iter: I,
    sep: &'a T,
    remaining: Option<Cow<'a, [T]>>,
    ended: bool,
}

impl<'a, T, I> FlatSplit<'a, T, I>
where
    T: PartialEq + Clone + 'a,
    I: Iterator<Item = &'a [T]>,
{
    fn new(iter: I, sep: &'a T) -> Self {
        Self {
            iter,
            sep,
            remaining: None,
            ended: false,
        }
    }
}

impl<'a, T, I> Iterator for FlatSplit<'a, T, I>
where
    T: PartialEq + Clone + 'a,
    I: Iterator<Item = &'a [T]>,
{
    type Item = Cow<'a, [T]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }

        // tell the borrow checker that we're not doing unsafe stuff
        let (ended, remaining, sep) = (&mut self.ended, &mut self.remaining, self.sep);

        match remaining {
            Some(Cow::Borrowed(ref mut slice)) => {
                // remaining slice is borrowed
                let idx = slice.iter().position(|x| x == sep);
                match idx {
                    Some(i) => {
                        // if we have a separator in the remaining slice
                        // split it and return the part before the separator
                        let (before, after) = slice.split_at(i);
                        *slice = &after[1..];

                        Some(Cow::Borrowed(before))
                    }
                    None => {
                        let next = self.iter.next();
                        match next {
                            None => {
                                // if we have reached the end of the iterator
                                // return the remaining slice and mark the iterator as ended
                                *ended = true;
                                Some(Cow::Borrowed(slice))
                            }
                            Some(next) => {
                                // if we have a next slice
                                // clone the existing slice
                                // and extend it with the next one
                                // and recurse
                                let mut before = slice.to_vec();
                                before.extend_from_slice(next);
                                *remaining = Some(Cow::Owned(before));
                                self.next()
                            }
                        }
                    }
                }
            }
            Some(Cow::Owned(ref mut slice)) => {
                // remaining slice already span multiple chunks
                let idx = slice.iter().position(|x| x == sep);
                match idx {
                    Some(i) => {
                        // if we already have a separator in the remaining slice
                        // split it and return the part before the separator
                        let mut before = slice.split_off(i);
                        std::mem::swap(slice, &mut before);

                        Some(Cow::Owned(before))
                    }
                    None => {
                        // no separator in the remaining slice
                        // get the next one from the iterator
                        let next = self.iter.next();
                        match next {
                            None => {
                                // if we have reached the end of the iterator
                                // return the remaining slice and mark the iterator as ended
                                *ended = true;
                                Some(Cow::Owned(std::mem::take(slice)))
                            }
                            Some(next) => {
                                // if we have a next slice
                                // extend the remaining slice with it
                                // and recurse
                                slice.extend_from_slice(next);
                                self.next()
                            }
                        }
                    }
                }
            }
            None => {
                // no remaining slice,
                // get the next one from the iterator
                // if it's empty, return None
                // otherwise set it as the remaining slice
                // and recurse
                let next = self.iter.next()?;
                self.remaining = Some(Cow::Borrowed(next));
                self.next()
            }
        }
    }
}

impl<'a, 's: 'a, T: PartialEq + Clone> ChunkedVec<T> {
    pub fn iter_split(&'a self, sep: &'s T) -> impl Iterator<Item = Cow<'a, [T]>> + 'a {
        FlatSplit::new(self.iter_chunks().map(|x| x.as_slice()), sep)
    }
}
