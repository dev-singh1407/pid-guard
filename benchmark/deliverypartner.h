#include<string>
#include<iostream>
using namespace std;
class deliverypartner{
    public:
    int id;
    string name;
    bool available;
    deliverypartner(int id,string name){
        this->id=id;
        this->name=name;
        availlable=true;

    }
    bool isavailable(){
        return available;

    }
    void assignorder(){
        return available;

    }
    void assignorder()
{
available=false;

}
void completedelivery(){
    available =true;
    
}
}