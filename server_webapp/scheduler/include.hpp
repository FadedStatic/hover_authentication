/*#pragma once

#include <iostream>
#include <thread>
#include <vector>
#include <span>
#include <Windows.h>

namespace scheduler
{
	struct task
	{
		std::string task_name;
		void(__cdecl* task_job)();
	};

	class scheduler_t
	{
		bool thread_running_{ false };
		std::thread scheduler_thread_;
		double scheduler_timing_ms_{ 16.6 };
		std::uint32_t scheduler_timing_hz_{ 60 };
	public:
		std::vector<task> task_list;

		void fire_all_tasks(), add_task(const task& task), remove_task(const std::uint32_t idx), remove_task(const std::string_view task_name), set_scheduler_rate(const std::uint32_t hz), start_scheduler(), stop_scheduler();

		scheduler_t(const std::span<task> list)
		{
			for (const auto& task : list)
				task_list.push_back(task);
		}
		scheduler_t() = default;

	};

	inline auto get()
	{
		return std::make_unique<scheduler_t>();
	}
}*/