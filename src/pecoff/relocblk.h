#pragma once
#ifndef _PECOFF_RELOCBLK_H_
#define _PECOFF_RELOCBLK_H_

#include <cinttypes>
#include <vector>
struct relocBlk
{
	uint16_t type : 4;
	uint16_t offset : 12;
};

#endif
