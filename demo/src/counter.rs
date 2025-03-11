use std::{
  fs,
  path::PathBuf,
  sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
  },
};

use tracing::{debug, info, trace, Level, Subscriber};
use tracing_subscriber::{fmt, prelude::*, registry::LookupSpan, EnvFilter, Layer};

// Create a static counter for steps
pub static STEP_COUNTER: AtomicUsize = AtomicUsize::new(0);

// Create a thread-safe vector to store the sequence
type SequenceType = Arc<Mutex<Vec<String>>>;
thread_local! {
    static SEQUENCE: SequenceType = Arc::new(Mutex::new(Vec::new()));
}

/// A custom layer to count steps and track sequence
pub struct StepCounterLayer;

impl<S> Layer<S> for StepCounterLayer
where S: Subscriber + for<'a> LookupSpan<'a>
{
  fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
    // Extract the message from the event
    let mut message = String::new();
    let mut visitor = MessageVisitor(&mut message);
    event.record(&mut visitor);

    // Count steps based on the message
    if message.contains("Proving single step") {
      STEP_COUNTER.fetch_add(1, Ordering::SeqCst);
    }

    // Track program counter for sequence
    if message.contains("Program counter = 0") {
      SEQUENCE.with(|seq| {
        let mut seq = seq.lock().unwrap();
        seq.push("even".to_string());
      });
    } else if message.contains("Program counter = 1") {
      SEQUENCE.with(|seq| {
        let mut seq = seq.lock().unwrap();
        seq.push("odd".to_string());
      });
    }
  }
}

// Helper to extract message from event
pub struct MessageVisitor<'a>(&'a mut String);

impl<'a> tracing::field::Visit for MessageVisitor<'a> {
  fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
    if field.name() == "message" {
      self.0.push_str(&format!("{:?}", value));
    }
  }
}

// Helper to get the current sequence
pub fn get_sequence() -> Vec<String> {
  SEQUENCE.with(|seq| {
    let seq = seq.lock().unwrap();
    seq.clone()
  })
}

// Helper to reset the sequence
pub fn reset_sequence() {
  SEQUENCE.with(|seq| {
    let mut seq = seq.lock().unwrap();
    seq.clear();
  });
}
