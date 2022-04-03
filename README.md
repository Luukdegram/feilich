# Feilich

Feilich is a TLS 1.3 implementation in [zig](https://ziglang.org). Zig has a great async model, allowing users to write concurrent programs.
However, most TLS libraries are written in C. Unfortunately, most of those libraries do not work well (or at all) with Zig's async.
Zig also produces small binaries as well has remarkable freestanding support. This, together with explicit allocators, allows us
to produce a library that also works for kernels and embedded devices. For those reasons, and the fact I've been wanting to
learn more about how TLS works, have made me decide to write this library.

The initial goal is to implement the server side of TLS 1.3 to make it work with my Gemini library [lemon_pie](https://github.com/Luukdegram/lemon_pie).
This is a great usecase as Gemini's specification requires the usage of TLS. As the usage of TLS 1.3 is not yet very widespread and many
libraries not offering full support for it yet, I do very much want to implement the client side of TLS 1.3 also. 

TLS 1.2 is not a goal as we already have a great TLS 1.2 library for zig called [iguanaTLS](https://github.com/alexnask/igunaTLS).
Although it currently only supports client side, we could perhaps PR server support in the future.

## Project status

The project is currently on-hold until I have more free time to work on this besides the self-hosted compiler for the Zig programming language.
I'd like to bring this project to the point where it's fully operational for a single cipher suite. From there on, it should be fairly straight
forward to implement more suites as well as other crypto algorithms supported by TLS 1.3.
I expect to be able to continue and get it to that state Q3/Q4 of this year. Until then, this project will be stale.

## Should I use this?

Maybe? I have no prior experience with TLS, nor am I some crypto expert. TLS contains some known [implementation pitfalls](https://datatracker.ietf.org/doc/html/rfc8446#appendix-C.3),
and can be quite complex to implement correctly. For those reasons alone I cannot recommend to use this library outside experimental, hobby usage.
It would be great to bring this library to a state where others and I could recommend its usage, tho I'm not sure that is possible with my lack
of knowledge and experience in this area.
