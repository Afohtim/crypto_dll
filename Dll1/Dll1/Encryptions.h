#pragma once
#include "AES.h"
#include "Kalyna.h"
#include "DES.h"
#include "Blowfish.h"

#ifdef ENCRYPTIONS_LIB_EXPORTS
#define ENCRYPTIONS_LIB_API __declspec(dllexport)
#else
#define ENCRYPTIONS_LIB_API __declspec(dllimport)
#endif


