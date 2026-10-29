#include "vehicle.h"
#include "parkingslot.h"
#include "ticket.h"
#include<vector>
#include<string>
#include<mutex>
using namespace std;
class parkinglot{
    private:
    vector<parkingslot>parkinglot;
    vector<ticket>tickets;
    int nextid=1;
    mutex mtx;
    public:
    parkinglot(int numberofslots){
        for(int i=1;i<=numberoflsots;i++){
            parkinglot.emplace_back(i);
        }
    }

    int  park(vehicle v){
        for(int i=0;i<parkinglot.size();i++){
            if(parkinglot[i].isoccupied()){
                parkinglot[i].park(v);
                int id=nextid++;
                tickets.emplace_back(id,i,v);

            }
            return nextid;

        }
    }
void remove(int ticketid){
    for(int i=0;i<tickets.size();i++){
        if(tickets[i].getticketid()==ticketid){
            ticket t=tickets[i];
            double seconds=difftime(time(nullptr),ticket.e)
        }
        if(t.type==vehicletype::car){
            return seconds*50;

        }

    }
}

}