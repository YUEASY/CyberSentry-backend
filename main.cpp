#include "main.h"
//DEFINE_bool(run_mode, false, "���������ģʽ��false-���ԣ� true-������");
//DEFINE_string(log_file, "", "����ģʽ�£�����ָ����־������ļ�");
//DEFINE_int32(log_level, 0, "����ģʽ�£�����ָ����־����ȼ�");



int main() {

    sp::logger::initLogger(false, "", 0);
    
    //std::thread httpServer(sp::runServer);
    //httpServer.join();

    sp::runServer();


    return 0;
}
