#pragma once
#ifndef _PECOFF_RELOCBLK_H_
#define _PECOFF_RELOCBLK_H_

#include <cinttypes>
#include <vector>
struct relocblk
{
	uint16_t offset : 12;
	uint16_t type : 4;
};

#endif
