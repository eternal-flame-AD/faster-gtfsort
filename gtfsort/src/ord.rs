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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdChain3<T0, T1, T2>(pub T0, pub T1, pub T2);

impl<T0, T1, T2> OrdChain3<T0, T1, T2> {
    #[inline(always)]
    pub fn new(t0: T0, t1: T1, t2: T2) -> Self {
        Self(t0, t1, t2)
    }
}

impl<T0, T1, T2> PartialOrd for OrdChain3<T0, T1, T2>
where
    T0: Ord,
    T1: Ord,
    T2: Ord,
{
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T0, T1, T2> Ord for OrdChain3<T0, T1, T2>
where
    T0: Ord,
    T1: Ord,
    T2: Ord,
{
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .cmp(&other.0)
            .then_with(|| self.1.cmp(&other.1))
            .then_with(|| self.2.cmp(&other.2))
    }
}
