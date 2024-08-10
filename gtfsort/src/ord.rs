use std::{cmp::Ordering, fmt::Debug, ops::Deref};

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct NaturalSort<S: AsRef<str>>(pub S);

impl<S: AsRef<str>> Deref for NaturalSort<S> {
    type Target = str;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<S: AsRef<str>> PartialEq for NaturalSort<S> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        natord::compare(self.0.as_ref(), other.0.as_ref()) == Ordering::Equal
    }
}

impl<S: AsRef<str>> Eq for NaturalSort<S> {}

impl<S: AsRef<str>> PartialOrd for NaturalSort<S> {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.0.as_ref().cmp(other.0.as_ref()))
    }
}

impl<S: AsRef<str>> Ord for NaturalSort<S> {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        natord::compare(self.0.as_ref(), other.0.as_ref())
    }
}
