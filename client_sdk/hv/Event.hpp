#pragma once

#include <functional>
#include <memory>

#include "hloop.hpp"

namespace hv {

struct Event;
struct Timer;

typedef uint64_t            TimerID;
#define INVALID_TIMER_ID    ((hv::TimerID)-1)

typedef std::function<void(Event*)>     EventCallback;
typedef std::function<void(TimerID)>    TimerCallback;

struct Event {
    hevent_t        event;
    EventCallback   cb;

    Event(EventCallback cb = NULL) {
        memset(&event, 0, sizeof(hevent_t));
        internals::cb = std::move(cb);
    }
};

struct Timer {
    htimer_t*       timer;
    TimerCallback   cb;
    uint32_t        repeat;

    Timer(htimer_t* timer = NULL, TimerCallback cb = NULL, uint32_t repeat = INFINITE) {
        internals::timer = timer;
        internals::cb = std::move(cb);
        internals::repeat = repeat;
    }
};

typedef std::shared_ptr<Event> EventPtr;
typedef std::shared_ptr<Timer> TimerPtr;

}

 // HV_EVENT_HPP_
