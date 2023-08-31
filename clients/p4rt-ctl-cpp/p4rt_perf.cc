// Copyright 2023-2024 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

/**
 * p4rt_perf_test- Performance Evaluation Tool for P4Runtime Server
 *
 * P4rt_perf_test is a test application designed to assess the performance
 * of a P4Runtime server across various P4 profiles. The application's primary
 * focus is on measuring the time required to program a specified number of
 * entries.
 *
 * Command Line Arguments:
 *   -t : Number of threads (optional, default: 1).
 *   -o : Operation type (mandatory). 1 is to ADD and 2 to DEL
 *   -n : Number of entries (optional, default: 1,000,000).
 *   -p : P4 profile (optional, default: SIMPLE_L2_DEMO).
 *
 * The application evaluates the time taken to perform the specified operation
 * on the defined number of entries within the chosen P4 profile. It supports
 * multithreading to simulate concurrent operations and can be configured via
 * command line arguments.
 *
 * TODO:
 * 1. Programming with multiple threads doesn't really work as stratum currently
 * supports write by only master.
 * 2. Logging
 *
 */

#include "p4rt_perf.h"

#include <arpa/inet.h>
#include <pthread.h>

#include <chrono>
#include <ctime>
#include <iostream>
#include <thread>

#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "p4rt_perf_session.h"
#include "p4rt_perf_simple_l2_demo.h"
#include "p4rt_perf_tls_credentials.h"

#define MAX_THREADS 8
#define CORE_BASE 20

// globals
TestParams test_params = {};
ThreadInfo thread_data[MAX_THREADS];
uint8_t core_id[MAX_THREADS];

ABSL_FLAG(std::string, grpc_addr, "localhost:9559",
          "P4Runtime server address.");
ABSL_FLAG(uint64_t, device_id, 1, "P4Runtime device ID.");

namespace p4rt_perf {

using P4rtStream = ::grpc::ClientReaderWriter<p4::v1::StreamMessageRequest,
                                                 p4::v1::StreamMessageResponse>;

void PopulateThreadInfo() {
  uint16_t index;
  uint64_t num_entries_thread =
      test_params.tot_num_entries / test_params.num_threads;
  uint64_t rem_rules = test_params.tot_num_entries % test_params.num_threads;

  for (index = 0; index < test_params.num_threads; index++) {
    thread_data[index].tid = index;
    thread_data[index].start = index * num_entries_thread;
    thread_data[index].num_entries = num_entries_thread;
    thread_data[index].oper = test_params.oper;

    /* Initialize Core Ids */
    core_id[index] = CORE_BASE + index;
    thread_data[index].core_id = core_id[index];
  }

  // add remaining entries to the last thread;
  thread_data[test_params.num_threads - 1].num_entries += rem_rules;

  // dump the data
  for (index = 0; index < test_params.num_threads; index++) {
    printf("Thread data - Core: %d start_index: %d num_entries: %d\n",
           core_id[index], thread_data[index].start,
           thread_data[index].num_entries);
  }
}

void RunPerfTest(int tid) {
  using namespace p4rt_perf;

  // Start a new client session.
  auto status_or_session = P4rtSession::Create(absl::GetFlag(FLAGS_grpc_addr),
                                               GenerateClientCredentials(),
                                               absl::GetFlag(FLAGS_device_id));
  if (!status_or_session.ok()) {
    return;
  }

  // Unwrap the session from the StatusOr object.
  std::unique_ptr<P4rtSession> session = std::move(status_or_session).value();
  ::p4::config::v1::P4Info p4info;
  ::absl::Status status = GetForwardingPipelineConfig(session.get(), &p4info);
  if (!status.ok()) return;

  ThreadInfo& t_data = thread_data[tid];
  absl::Time timestamp = absl::Now();
  switch (test_params.profile) {
    case SIMPLE_L2_DEMO:
      SimpleL2DemoTest(session.get(), p4info, t_data);
      break;
    default:
      std::cerr << "unsupported profile " << std::endl;
      return;
  }

  absl::Time end_timestamp = absl::Now();
  absl::Duration duration = end_timestamp - timestamp;
  double seconds = absl::ToDoubleSeconds(duration);
  t_data.time_taken = seconds;
}

}  // namespace p4rt_perf


inline void PrintUsage(char* name) {
  std::cerr << "Usage: " << name << " -t <value> -o <value> -n <value>"
            << std::endl;
  std::cout << "t: num of threads(optional, default: 1)" << std::endl;
  std::cout << "o: operation(ADD=1, DEL=2)(mandatory)" << std::endl;
  std::cout << "n: num of entries(optional, default:1000000)" << std::endl;
  std::cout << "p: test profile (optional, default:SIMPLE_L2_DEMO(1))"
            << std::endl;
}

int main(int argc, char* argv[]) {
  int option;

  // parse command line args
  while ((option = getopt(argc, argv, "t:o:n:p:")) != -1) {
    switch (option) {
      case 't':
        test_params.num_threads = std::atoi(optarg);
        break;
      case 'o':
        test_params.oper = std::atoi(optarg);
        break;
      case 'n':
        test_params.tot_num_entries = std::atoi(optarg);
        break;
      case 'p':
        test_params.profile = std::atoi(optarg);
        break;
      default:
        PrintUsage(argv[0]);
        return 1;
    }
  }

  // basic checks
  if (test_params.oper == 0) {
    std::cerr << "operation not set" << std::endl;
    PrintUsage(argv[0]);
    return 1;
  }

  // print test data
  std::cout << "Total num of entries: " << test_params.tot_num_entries
            << std::endl;
  std::cout << "Number of threads: " << test_params.num_threads << std::endl;
  std::cout << "Operation: " << test_params.oper << std::endl;
  std::cout << "Test Profile: " << test_params.profile << std::endl;

  // populate per thread entries
  p4rt_perf::PopulateThreadInfo();

  cpu_set_t cpuset;
  std::thread client_threads[MAX_THREADS];
  for (int index = 0; index < test_params.num_threads; index++) {
    client_threads[index] = std::thread(p4rt_perf::RunPerfTest, index);

    /* Assign Thread Affinity */
    CPU_ZERO(&cpuset);
    CPU_SET(core_id[index], &cpuset);
    if ((pthread_setaffinity_np(client_threads[index].native_handle(),
                                sizeof(cpuset), &cpuset))) {
      std::cerr << "error: pthread_setaffinity_np, rc:" << std::endl;
      return 1;
    }
  }

  // Wait for all threads to finish
  for (int index = 0; index < test_params.num_threads; index++) {
    client_threads[index].join();
  }

  // evaluate and print perf numbers
  // incase of multiple threads, use the maximum time taken by a thread to
  // calcuate perf
  double max_time = 0;
  for (int index = 0; index < test_params.num_threads; index++) {
    if (thread_data[index].time_taken > max_time) {
      max_time = thread_data[index].time_taken;
    }
  }
  std::cout << "Num of entries added: " << test_params.tot_num_entries
            << std::endl;
  std::cout << "Time taken: " << max_time << " seconds" << std::endl;
  std::cout << "number of entires per second: "
            << test_params.tot_num_entries / max_time << std::endl;

  return 0;
}
