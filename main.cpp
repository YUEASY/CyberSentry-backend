#include "main.h"
//DEFINE_bool(run_mode, false, "程序的运行模式，false-调试； true-发布；");
//DEFINE_string(log_file, "", "发布模式下，用于指定日志的输出文件");
//DEFINE_int32(log_level, 0, "发布模式下，用于指定日志输出等级");



static void listenForExit() {
    std::cout << "press ESC to stop server" << std::endl;
    while (sp::running.load()) {
        if (_kbhit()) { // 检测键盘是否有输入
            int ch = _getch();
            if (ch == 27) { // 27 = ESC 键的 ASCII 码
                std::cout << "\nESC pressed. Stopping server...\n";
                sp::running.store(false);
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main() {

    sp::logger::initLogger(false, "", 0);
    
    std::thread httpServer(sp::runServer);
    std::thread keyboardListener(listenForExit);

    keyboardListener.join(); 
    std::cout << "Shutting down server...\n";

    httpServer.join(); 
    std::cout << "Server stopping...\n";


    return 0;
}
