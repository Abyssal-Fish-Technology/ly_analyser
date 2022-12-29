#pragma once
#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <vector>
#include <queue>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <future>
#include <functional>
#include <stdexcept>

namespace threadpool
{
//线程池,可以提交变参函数或lambda的匿名函数执行,可以获取执行返回值
class Threadpool
{
  private:
    // 线程池
    std::vector<std::thread> pool;
    // 任务队列
    std::queue<std::function<void()> > tasks;
    // 同步
    std::mutex m_lock;
    // 条件阻塞
    std::condition_variable cv_task;
    // 是否关闭提交
    std::atomic<bool> stoped;
    //空闲线程数量
    std::atomic<int>  idlThrNum;

  public:
    Threadpool(int size) : stoped(false)
    {
      idlThrNum = size < 1 ? 1 : size;
      for (size = 0; size < idlThrNum; ++size)
      { 
        pool.emplace_back(
          [this]
          { 
            while(!this->stoped)
            {
              std::function<void()> task;
              {   // 获取一个待执行的 task
                std::unique_lock<std::mutex> lock{ this->m_lock };
                this->cv_task.wait(lock,
                  [this] {
                      return this->stoped.load() || !this->tasks.empty();
                  }
                ); // wait 直到有 task
                if (this->stoped && this->tasks.empty())
                  return;
                task = std::move(this->tasks.front()); // 取一个 task
                this->tasks.pop();
              }
              idlThrNum--;
              task();
              idlThrNum++;
            }
          }
        );
      }
    }

    ~Threadpool()
    {
      stoped.store(true);
      cv_task.notify_all(); // 唤醒所有线程执行
      for (std::thread& thread : pool) {
        //thread.detach(); // 让线程自生自灭
        if(thread.joinable())
          thread.join(); // 等待任务结束，前提：线程一定会执行完
      }
    }

  public:
    // 提交一个任务
    // 调用.get()获取返回值会等待任务执行完,获取返回值
    template<class F, class... Args>
    auto commit(F&& f, Args&&... args) ->std::future<decltype(f(args...))>
    {
      if (stoped.load())    // stop == true ??
        throw std::runtime_error("commit on ThreadPool is stopped.");

      using RetType = decltype(f(args...)); // typename std::result_of<F(Args...)>::type, 函数 f 的返回值类型
      auto task = std::make_shared<std::packaged_task<RetType()> >(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)); 
      std::future<RetType> future = task->get_future();
      {    // 添加任务到队列
        std::lock_guard<std::mutex> lock{ m_lock };
        tasks.emplace(
          [task]()
          { 
            (*task)();
          });
      }
      cv_task.notify_one(); // 唤醒一个线程执行

      return future;
    }

    //空闲线程数量
    int idlCount() { return idlThrNum; }

};

}

#endif
