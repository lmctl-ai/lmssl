// Recording executable, adapted from lmdraw's Windows shim. No shell is involved.
#include <filesystem>
#include <algorithm>
#include <cstdio>
#include <iterator>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#ifdef _WIN32
#include <process.h>
#include <fcntl.h>
#include <io.h>
#define dup _dup
#define dup2 _dup2
#define close _close
#define fileno _fileno
#else
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#endif
int main(int argc, char **argv) {
  if (argc < 7) return 125;
#ifdef _WIN32
  _setmode(_fileno(stdout), _O_BINARY);
  _setmode(_fileno(stderr), _O_BINARY);
#endif
  try {
    // MODE HOST STATUS CAPTURE --lmcode FILE...
    if (std::string(argv[5]) != "--lmcode") return 125;
    if (*argv[4]) {
      std::filesystem::create_directories(argv[4]);
      int part = 0;
      for (int i=6; i<argc; ++i) {
        if (i != 6 && std::string(argv[i-1]) != "--lmcode") continue;
        auto target = std::filesystem::path(argv[4]) / (std::to_string(part++)+".lmcode");
        // Compiler inputs are read-only. Repeated sweep cases must replace our copy,
        // including on Windows where readonly files cannot be removed directly.
        if (std::filesystem::exists(target)) {
          std::filesystem::permissions(target, std::filesystem::perms::owner_write,
                                       std::filesystem::perm_options::add);
          std::filesystem::remove(target);
        }
        std::filesystem::copy_file(argv[i], target);
      }
    }
    int code = 0;
    if (std::string(argv[1]) == "--capture-host") {
      std::cout << "LMCODE_RETURN_BEGIN\n{\"ok\":true,\"result\":null}\nLMCODE_RETURN_END\n";
    } else {
      std::string output = std::string(argv[3]) + ".stdout";
      FILE *record = std::fopen(output.c_str(), "wb");
      if (!record) return 125;
      int saved = dup(fileno(stdout));
      if (saved < 0 || dup2(fileno(record), fileno(stdout)) < 0) return 125;
      std::vector<char*> args{argv[2]};
      for (int i=5; i<argc; ++i) args.push_back(argv[i]);
      args.push_back(nullptr);
#ifdef _WIN32
      auto status = _spawnv(_P_WAIT, argv[2], args.data());
      code = status < 0 ? 125 : static_cast<int>(status);
#else
      pid_t pid = fork();
      if (pid < 0) return 125;
      if (pid == 0) { execv(argv[2], args.data()); _exit(125); }
      int status;
      while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return 125;
      code = WIFEXITED(status) ? WEXITSTATUS(status) : 125;
#endif
      std::fflush(stdout);
      if (dup2(saved, fileno(stdout)) < 0) return 125;
      close(saved);
      std::fclose(record);
      std::ifstream input(output, std::ios::binary);
      std::string frame((std::istreambuf_iterator<char>(input)), {});
      // Fail if upstream chatter contaminates any invocation, including sweep cases.
      const std::string end = "LMCODE_RETURN_END\n";
      if (frame.rfind("LMCODE_RETURN_BEGIN\n", 0) != 0 || frame.size() < end.size() ||
          frame.compare(frame.size()-end.size(), end.size(), end) != 0 ||
          std::count(frame.begin(), frame.end(), '\n') != 3) {
        std::cerr << "recording shim: invalid terminal frame\n";
        code = 125;
      }
      std::cout << frame;
    }
    std::ofstream(argv[3]) << code;
    return code;
  } catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 125; }
}
