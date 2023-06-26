#pragma once
#include "Imgui/imgui.h"


void DrawBox(float X, float Y, float W, float H, const ImU32& color, int thickness)
{
	ImDrawList* Drawlist = ImGui::GetBackgroundDrawList();

	Drawlist->AddRect(ImVec2(X + 1, Y + 1), ImVec2(((X + W) - 1), ((Y + H) - 1)), ImGui::GetColorU32(color), thickness);
	Drawlist->AddRect(ImVec2(X, Y), ImVec2(X + W, Y + H), ImGui::GetColorU32(color), thickness);
}