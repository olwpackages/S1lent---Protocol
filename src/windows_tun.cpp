#include "s1lent/ip_interface.hpp"
#include <algorithm>
#include <limits>
#include <memory>
#ifdef _WIN32
#include <windows.h>
#else
#endif

namespace s1lent {
#ifdef _WIN32
struct WindowsTunInterface::Functions {
    using Adapter=void*;using Session=void*;
    HMODULE dll{};Adapter adapter{};Session session{};bool created{};
    Adapter (WINAPI* openAdapter)(LPCWSTR){};
    Adapter (WINAPI* createAdapter)(LPCWSTR,LPCWSTR,const GUID*){};
    void (WINAPI* closeAdapter)(Adapter){};
    Session (WINAPI* startSession)(Adapter,DWORD){};
    void (WINAPI* endSession)(Session){};
    BYTE* (WINAPI* receivePacket)(Session,DWORD*){};
    void (WINAPI* releaseReceivePacket)(Session,const BYTE*){};
    BYTE* (WINAPI* allocateSendPacket)(Session,DWORD){};
    void (WINAPI* sendPacket)(Session,const BYTE*){};
    HANDLE (WINAPI* getReadWaitEvent)(Session){};
};
namespace {
template<class T> bool symbol(HMODULE dll,const char* name,T& out){out=reinterpret_cast<T>(GetProcAddress(dll,name));return out!=nullptr;}
std::string winError(const char* message){return std::string(message)+" (Windows error "+std::to_string(GetLastError())+")";}
}
WindowsTunInterface::WindowsTunInterface()=default;
WindowsTunInterface::~WindowsTunInterface(){if(!functions_)return;if(functions_->session)functions_->endSession(functions_->session);if(functions_->adapter)functions_->closeAdapter(functions_->adapter);if(functions_->dll)FreeLibrary(functions_->dll);delete functions_;}
bool WindowsTunInterface::open(const std::wstring& name,std::string* error){
    if(functions_){if(error)*error="Wintun interface is already open";return false;}
    auto f=std::make_unique<Functions>();f->dll=LoadLibraryExW(L"wintun.dll",nullptr,LOAD_LIBRARY_SEARCH_APPLICATION_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
    if(!f->dll){if(error)*error=winError("cannot load wintun.dll from the application or system directory");return false;}
    const bool loaded=symbol(f->dll,"WintunOpenAdapter",f->openAdapter)&&symbol(f->dll,"WintunCreateAdapter",f->createAdapter)&&
        symbol(f->dll,"WintunCloseAdapter",f->closeAdapter)&&symbol(f->dll,"WintunStartSession",f->startSession)&&
        symbol(f->dll,"WintunEndSession",f->endSession)&&symbol(f->dll,"WintunReceivePacket",f->receivePacket)&&
        symbol(f->dll,"WintunReleaseReceivePacket",f->releaseReceivePacket)&&symbol(f->dll,"WintunAllocateSendPacket",f->allocateSendPacket)&&
        symbol(f->dll,"WintunSendPacket",f->sendPacket)&&symbol(f->dll,"WintunGetReadWaitEvent",f->getReadWaitEvent);
    if(!loaded){if(error)*error="wintun.dll is missing a required API export";FreeLibrary(f->dll);return false;}
    f->adapter=f->openAdapter(name.c_str());if(!f->adapter){f->adapter=f->createAdapter(name.c_str(),L"S1lent",nullptr);f->created=f->adapter!=nullptr;}
    if(!f->adapter){if(error)*error=winError("cannot open or create Wintun adapter");FreeLibrary(f->dll);return false;}
    f->session=f->startSession(f->adapter,0x400000);
    if(!f->session){if(error)*error=winError("WintunStartSession failed");f->closeAdapter(f->adapter);FreeLibrary(f->dll);return false;}
    functions_=f.release();return true;
}
bool WindowsTunInterface::read(Bytes& packet,std::chrono::milliseconds timeout){
    if(!functions_||!functions_->session)return false;DWORD size=0;BYTE* data=functions_->receivePacket(functions_->session,&size);
    if(data){packet.assign(data,data+size);functions_->releaseReceivePacket(functions_->session,data);return true;}
    if(GetLastError()!=ERROR_NO_MORE_ITEMS)return false;
    const auto count=std::clamp<std::int64_t>(timeout.count(),0,MAXDWORD);WaitForSingleObject(functions_->getReadWaitEvent(functions_->session),static_cast<DWORD>(count));
    data=functions_->receivePacket(functions_->session,&size);if(!data)return false;packet.assign(data,data+size);functions_->releaseReceivePacket(functions_->session,data);return true;
}
bool WindowsTunInterface::write(std::span<const Byte> packet,std::string* error){
    if(!functions_||!functions_->session||packet.empty()||packet.size()>65535){if(error)*error="invalid or unopened Wintun packet";return false;}
    BYTE* target=functions_->allocateSendPacket(functions_->session,static_cast<DWORD>(packet.size()));if(!target){if(error)*error=winError("Wintun packet ring is full or unavailable");return false;}
    std::copy(packet.begin(),packet.end(),target);functions_->sendPacket(functions_->session,target);return true;
}
#else
struct WindowsTunInterface::Functions {};
WindowsTunInterface::WindowsTunInterface()=default;
WindowsTunInterface::~WindowsTunInterface()=default;
bool WindowsTunInterface::open(const std::wstring&,std::string* error){if(error)*error="Wintun is available only on Windows";return false;}
bool WindowsTunInterface::read(Bytes&,std::chrono::milliseconds){return false;}
bool WindowsTunInterface::write(std::span<const Byte>,std::string* error){if(error)*error="Wintun is available only on Windows";return false;}
#endif
} // namespace s1lent
