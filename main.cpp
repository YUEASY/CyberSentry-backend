#include "main.h"
//DEFINE_bool(run_mode, false, "���������ģʽ��false-���ԣ� true-������");
//DEFINE_string(log_file, "", "����ģʽ�£�����ָ����־������ļ�");
//DEFINE_int32(log_level, 0, "����ģʽ�£�����ָ����־����ȼ�");



static void listenForExit() {
    std::cout << "press ESC to stop server" << std::endl;
    while (sp::running.load()) {
        if (_kbhit()) { // �������Ƿ�������
            int ch = _getch();
            if (ch == 27) { // 27 = ESC ���� ASCII ��
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
