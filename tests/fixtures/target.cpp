// Integration-test target. Built with /GR- (RTTI off) like Unreal modules,
// so dynamic_type has to work from vftable symbols alone.
#include <windows.h>
#include <cstdio>

struct FState { int Counter; float Speed; };
FState g_State = { 0, 1.5f };

// bitfield write test: writing bB must not clobber its neighbours in the same byte
struct FFlags { unsigned char bA : 1; unsigned char bB : 1; unsigned char Mode : 3; unsigned char Other; };
FFlags g_Flags = { 1, 0, 5, 7 };

struct FBase
{
    virtual ~FBase() = default;
    virtual int Kind() const { return 0; }
    int BaseValue = 11;
};

struct FDerived : FBase
{
    int Kind() const override { return 1; }
    int DerivedValue = 22;
};

FBase* g_Object = nullptr;

__declspec(noinline) int Accumulate(int Delta)
{
    int Sum = g_State.Counter + Delta;
    return Sum;
}

__declspec(noinline) void Tick()
{
    g_State.Counter = Accumulate(1); // LINE_TICK_BODY
}

int main()
{
    g_Object = new FDerived();
    for (;;)
    {
        Tick();
        std::printf("%d %.2f %d\n", g_State.Counter, g_State.Speed, g_Object->Kind());
        std::fflush(stdout);
        Sleep(100);
    }
}
