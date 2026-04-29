#lang forge

open "variant_1.frg"

test expect {
  train_predictor_sets_up_hardware: {
    some s, next: State | {
      train_predictor[s, next]
      next.prediction != LikelyInBounds
    }
  } is unsat

  train_predictor_is_passive: {
    some s, next: State | {
      train_predictor[s, next]
      (s.cache != next.cache or s.attackerKnowledge != next.attackerKnowledge)
    }
  } is unsat

  train_predictor_switches_owner: {
    some s, next: State | {
      train_predictor[s, next]
      s.owner = Attacker
      next.owner = Victim
    }
  } is sat
}

test expect {
  bypass_requires_misprediction_state: {
    some s, next: State, idx: Int | {
      s.prediction != LikelyInBounds
      speculative_bounds_bypass[s, next, idx]
    }
  } is unsat

  bypass_enforces_out_of_bounds: {
    some s, next: State, idx: Int | {
      idx <= Memory.array1_size
      speculative_bounds_bypass[s, next, idx]
    }
  } is unsat

  bypass_resets_prediction_state: {
    some s, next: State, idx: Int | {
      speculative_bounds_bypass[s, next, idx]
      next.prediction != Unknown
    }
  } is unsat

  bypass_updates_cache: {
    some s, next: State, idx: Int | {
      speculative_bounds_bypass[s, next, idx]
      Memory.array1[idx] not in next.cache
    }
  } is unsat
}

test expect {

  attacker_must_own_to_read_cache: {
    some s, next: State | {
      s.owner != Attacker
      attacker_cache[s, next]
    }
  } is unsat

  attacker_learns_from_cache: {
    some s, next: State, addr: Address | {
      addr in s.cache
      addr not in s.attackerKnowledge
      attacker_cache[s, next]
      addr in next.attackerKnowledge
    }
  } is sat

  no_cache_no_new_knowledge: {
    some s, next: State | {
      no s.cache
      attacker_cache[s, next]
      s.attackerKnowledge != next.attackerKnowledge
    }
  } is unsat
}