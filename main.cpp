#include "main.h"
//DEFINE_bool(run_mode, false, "程序的运行模式，false-调试； true-发布；");
//DEFINE_string(log_file, "", "发布模式下，用于指定日志的输出文件");
//DEFINE_int32(log_level, 0, "发布模式下，用于指定日志输出等级");



int main() {

    sp::logger::initLogger(false, "", 0);
    
    //std::thread httpServer(sp::runServer);
    //httpServer.join();

    sp::runServer();


    return 0;
}
