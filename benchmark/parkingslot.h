#include"vehicle.h"
#include<string>
using namespace std;
class parkingslot{
    string vehicle_number;
    vehicletype type;
    int slotid;
    bool occupied;
    parkingslot(string vehicle_number,vehicletype type,int slotid,bool occupied){
        this->vehicle_number=vehicle_number;
        this->type=vehicletype::car;
        this->slotid=slotid;
        this->occupied=false;

    }
    bool isoccupied(){
        return !occupied;

    }
    void park(vehicle v){
        this->occupied=true;
        this->vehicle_number=v.number;
        type=v.type;


    }
    void remove(){
        
    }



};
