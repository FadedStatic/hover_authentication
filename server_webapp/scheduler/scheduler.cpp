/*#include "include.hpp"

namespace scheduler
{
	void scheduler_t::add_task(const task& task)
	{
		task_list.emplace_back(task);
	}

	void scheduler_t::fire_all_tasks()
	{
		for (const auto& [task_name, task_job] : task_list)
		{
			std::thread(task_job).join();
		}
	}

	void scheduler_t::remove_task(const std::string_view task_name)
	{
		std::vector<task> tasks_copy;

		for (const auto& [taskname, taskjob] : task_list)
		{
			if (task_name == taskname)
			{
				continue;
			}
			tasks_copy.emplace_back(taskname);
		}
		task_list = tasks_copy;
	}

	void scheduler_t::remove_task(const std::uint32_t idx)
	{
		std::vector<task> tasks_copy;
		std::uint32_t counter{ 0 };
		for (const auto& [taskname, taskjob] : task_list)
		{
			if (idx == counter++)
			{
				continue;
			}
			tasks_copy.emplace_back(taskname);
		}
		task_list = tasks_copy;
	}

	void scheduler_t::set_scheduler_rate(const std::uint32_t hz)
	{
		scheduler_timing_hz_ = hz;
		scheduler_timing_ms_ = 1000 / hz;
	}

	void scheduler_t::start_scheduler()
	{
		if (thread_running_)
			return;

		thread_running_ = true;
		scheduler_thread_ = std::thread([this]
			{
				do
				{
					Sleep(scheduler_timing_ms_);
					fire_all_tasks();
				} while (thread_running_);
			});
		scheduler_thread_.detach();
	}

	void scheduler_t::stop_scheduler()
	{
		thread_running_ = false;
	}


}*/