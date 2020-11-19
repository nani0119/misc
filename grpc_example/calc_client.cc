#include "calc_client.h"
#include <algorithm>

int main(int argc, char const *argv[])
{
    std::vector<int> v;
    std::string target = "127.0.0.1:50051";
    CalculateClient client(grpc::CreateChannel(target, grpc::InsecureChannelCredentials()));
    int sum = client.addTwoInts(1,2);
    std::cout << "addTwoInts result:" << sum << std::endl;

    v.resize(10);
    std::fill_n(v.begin(), 10, 1);
    sum = client.addTotal(v, 10);
    std::cout << "addTotal result:" << sum << std::endl;

    sum = client.getRandomTotal();
    std::cout << "getRandomTotal result:" << sum << std::endl;

    sum = client.exchangeRamdomTotal();
    std::cout << "exchangeRamdomTotal result:" << sum << std::endl;
    return 0;
}
