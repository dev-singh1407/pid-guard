#include<string>
using namespace std;
enum class vehicletype{
    car,bike
};
class vehicle{
   public: string number;
    vehicletype type;
    vehicle(string number,vehicletype type){
        this->number=number;
        this->type=type;

    }

};
