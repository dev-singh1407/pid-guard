#include"parkingslot.h"
#include"vehicle.h"
#include<ctime>
using namespace std;
class ticket{
    int ticketid;
    string vehicle_number;
    time_t entrytime;
    vehicletype type;
    int slotindex;
    ticket(int ticketid,string vehicle_number,vehicletype type,time_t entrytime){
        this->ticketid=ticketid;
        this->type=vehicletype::car;
        this->vehicle_number="";
        this->entrytime=time(nullptr);

    }

};
