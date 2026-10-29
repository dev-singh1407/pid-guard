#include<string>
using namespace std;
class customer
{
    public:
    string name;
    string address;
    int id;
    customer(string name,string address,int id){
        this->name=name;
        this->address=address;
        this->id=id;
    }
}