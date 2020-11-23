#include <algorithm>
#include "calc_client.h"
#include "health_check_client.h"


int main(int argc, char const *argv[])
{
    std::vector<int> v;
    std::string target = "127.0.0.1:50051";
    std::cout <<"grpc version:"<< grpc::Version() << std::endl;
    HealthCheck healthCheck(grpc::CreateChannel(target, grpc::InsecureChannelCredentials()));

    if(healthCheck.check("calcSyncService"))
    {
        std::cout << "calcSyncService is serving" << std::endl;
    }
    else
    {
        std::cout << "calcSyncService is not serving" << std::endl;
        return 0;
    }
    

    CalculateClient client(grpc::CreateChannel(target, grpc::InsecureChannelCredentials()));
    int sum = client.addTwoInts(1,2);
    std::cout << "addTwoInts result:" << sum << std::endl;
#if 0
    v.resize(10);
    std::fill_n(v.begin(), 10, 1);
    sum = client.addTotal(v, 10);
    std::cout << "addTotal result:" << sum << std::endl;

    sum = client.getRandomTotal();
    std::cout << "getRandomTotal result:" << sum << std::endl;

    sum = client.exchangeRamdomTotal();
    std::cout << "exchangeRamdomTotal result:" << sum << std::endl;
#endif
    CalculateAsyncClient asyncClient(grpc::CreateChannel(target, grpc::InsecureChannelCredentials()));
    asyncClient.getPlusOne(1);
    std::thread t{&CalculateAsyncClient::asyncCompleteRpc, &asyncClient};
    t.join();

    return 0;
}
