# Hover Authentication System

This is the source code to a project I was working a while back, which was essentially just an experiment for a very lightweight server and client for managing software license access, on a timed basis. 
Users were supposed to be able to complete advertisements through monetization networks to gain access.

This project did not end up being used in any of my projects, so I decided to open source it with some redactions and other things for security reasons.

## Features
- Uses C++ as the webserver backend, so it is fast by nature. (Using Drogon)
- Client library is available in JavaScript, C++/CLI (For use in C# projects), and C++ native.
- Client library implements registry key saving of credentials, for ease of use.

## Issues
- Drogon is not meant for use in production, as it is maintained by a small group of developers. Ideally, this project would be written in Rust and use Actix. I have done this for another project of mine, but that code will not be released publicly.
- Client currently hashes the information itself, which was done to save computing costs on the server BUT this should never be done in production.
- Server currently does not use a database, instead it uses a text file. This was supposed to be a temporary implementation, but adding support for Redis or Postgresql was never exactly a priority.
- A lot of client code does not have much error handling, as implementing that for an SDK would be tricky and I was not able to make a decision as to how I could standardize that.

### License
You can use this project however you like, I'm not going to put it under any license.