#lang forge


sig Address {}
sig Value {}

sig State {
  pc: one Address,
  btb: pfunc Address -> Address, 
  cache: set Address,
  regs: pfunc Int -> Address 
}

pred jalr[s: State, rs1_idx: Int, next: State] {
  let target = s.regs[rs1_idx] |
    next.pc = target
}


pred train_btb[s: State, branch_pc: Address, malicious_target: Address, next: State] {
  next.btb = s.btb + (branch_pc -> malicious_target)
  next.pc = s.pc 
  next.cache = s.cache
}


pred speculative_jump[s: State, branch_pc: Address, next: State] {

  some predicted_target: Address | {
    s.btb[branch_pc] = predicted_target
    next.pc = predicted_target

    next.cache = s.cache + predicted_target
  }
}

test expect {
  leak_possible: {
    some s0, s1, s2: State | {

      train_btb[s0, s0.pc, s1.regs[5], s1]

      speculative_jump[s1, s1.pc, s2]

      s2.cache != s0.cache
    }
  } is sat
}