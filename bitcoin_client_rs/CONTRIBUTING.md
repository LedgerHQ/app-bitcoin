# Contributing to `bitcoin_client_rs`

## Workflow

The codebase is maintained using the "contributor workflow" where everyone
without exception contributes patch proposals using "pull requests" (PRs). This
facilitates social contribution, easy testing and peer review.

In general, [commits should be atomic](https://en.wikipedia.org/wiki/Atomic_commit#Atomic_commit_convention)
and diffs should be easy to read. For this reason, do not mix any formatting
fixes or code moves with actual code changes.

When possible, make sure each individual commit is hygienic: that it builds successfully
on its own without warnings, errors, regressions, or test failures.

Commit messages should be verbose by default consisting of a short subject line,
a blank line and detailed explanatory text as separate paragraph(s), unless the
title alone is self-explanatory. Commit messages should be helpful to people
reading your code in the future, so explain the reasoning for your decisions.

If your pull request contains fixup commits (commits that change the same line of 
code repeatedly) or too fine-grained commits, you may be asked to 
[squash](https://git-scm.com/docs/git-rebase#_interactive_mode) your commits 
before it will be merged.

Patchsets should always be focused. For example, a pull request could add a
feature, fix a bug, or refactor code; but not a mixture. Please also avoid super
pull requests which attempt to do too much, are overly large, or overly complex
as this makes review difficult. Instead, prefer opening different focused pull requests.


## Minimum Supported Rust Version

`bitcoin_client_rs` must compile with **Rust 1.78**, the `rust-version` declared in
Cargo.toml.

The tests need **Rust 1.85**, which their `hex-literal` dependency requires.

## Style

Use [`rustfmt`](https://github.com/rust-lang/rustfmt) and
[Clippy](https://github.com/rust-lang/rust-clippy).
