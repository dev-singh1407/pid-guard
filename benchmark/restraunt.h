#include"menuitem.h"
using namespace std;
#include<vector>
class restraunt{
    string name;
    int id;
    vector<menuitem>menu;
    restraunt(int id,string name){
        this->id=id;
        this->name=name;

    }
    void additem(){
        menu.push_back(item);

    }

    void showmenue(){
        for(int i=0i;i<menu.size();i++){
            menu[i].display();

        }
    }
menuitem getmenuitem(int itemid){
    for(int i=0;i<menu.size();i++){
        if(menu[i].id==itemid){
            return menu[i];
            
        }
    }
}

}