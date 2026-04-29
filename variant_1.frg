#lang forge

// this file shows the conditional branch predictor variation of the Spectre attack

abstract sig Principal {}

one sig Victim, Attacker extends Principal {}

sig Address {}

abstract sig PredictionStatus {}

one sig LikelyInBounds, Unknown extends PredictionStatus {}

one sig Memory {
    array1: pfunc Int -> Address,
    array1_size: one Int,
    secretIndex: one Int
}

sig State {
    owner: one Principal,
    cache: set Address,
    attackerKnowledge: set Address,
    prediction: one PredictionStatus
}

// making the CPU "trust" the bounds too much 
pred train_predictor[s: State, next: State] {
    s.owner = Attacker
    next.prediction = LikelyInBounds
    next.owner = Victim
    next.cache = s.cache
    next.attackerKnowledge = s.attackerKnowledge
}

// here is where the attacker makes the victim access memory they should not be able to access
pred speculative_bounds_bypass[s: State, next: State, malicious_idx: Int] {
    s.owner = Victim

    s.prediction = LikelyInBounds

    malicious_idx > Memory.array1_size 

    let secretVal = Memory.array1[malicious_idx] | {
        next.cache = s.cache + secretVal
    }
    
    next.owner = Attacker
    next.attackerKnowledge = s.attackerKnowledge
    next.prediction = Unknown
}

// here is where the attacker actually gets the memory 
pred attacker_cache[s: State, next: State] {
    s.owner = Attacker
    next.attackerKnowledge = s.attackerKnowledge + s.cache
    next.cache = s.cache
    next.owner = Attacker
}

test expect {
  full_spectre_v1_leak: {
    some s0, s1, s2, s3: State | {
        no s0.cache
        no s0.attackerKnowledge

        Memory.array1_size > 0

        Memory.secretIndex > Memory.array1_size

        all i: Int | (i >= 0 and i <= Memory.array1_size) implies {
            Memory.array1[i] != Memory.array1[Memory.secretIndex]
            one Memory.array1[i]
        }

        one mal_idx: Int | {
            mal_idx = Memory.secretIndex
            
            train_predictor[s0, s1]
            speculative_bounds_bypass[s1, s2, mal_idx]
            attacker_cache[s2, s3]

            Memory.array1[mal_idx] in s3.attackerKnowledge
            Memory.array1[mal_idx] not in s0.attackerKnowledge
        }
    }
  } is sat
}
