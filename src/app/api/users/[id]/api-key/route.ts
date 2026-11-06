import { NextResponse, NextRequest } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser, isAdmin, generateApiKey } from "@/lib/api-auth";

export const dynamic = "force-dynamic";

/**
 * Admin-side API key management for another user (tenant provisioning).
 * Unlike /api/user/api-key (dashboard-only, acts on yourself), these accept
 * an X-API-Key from a SUPERADMIN, so an external system can provision tenants
 * end-to-end without logging into the dashboard.
 */

// POST: generate (or rotate) the API key of user {id}. The old key stops working immediately.
export async function POST(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    const user = await getAuthenticatedUser(request);
    if (!user || !isAdmin(user.role)) {
        return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 403 });
    }

    const { id } = await params;

    try {
        const target = await prisma.user.findUnique({ where: { id }, select: { id: true } });
        if (!target) {
            return NextResponse.json({ status: false, message: "User not found", error: "User not found" }, { status: 404 });
        }

        const apiKey = generateApiKey();
        await prisma.user.update({ where: { id }, data: { apiKey } });

        return NextResponse.json({ status: true, message: "API key generated", data: { userId: id, apiKey } });
    } catch (error) {
        console.error("Admin generate API key error:", error);
        return NextResponse.json({ status: false, message: "Failed to generate API key", error: "Failed to generate API key" }, { status: 500 });
    }
}

// DELETE: revoke the API key of user {id}.
export async function DELETE(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    const user = await getAuthenticatedUser(request);
    if (!user || !isAdmin(user.role)) {
        return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 403 });
    }

    const { id } = await params;

    try {
        const target = await prisma.user.findUnique({ where: { id }, select: { id: true } });
        if (!target) {
            return NextResponse.json({ status: false, message: "User not found", error: "User not found" }, { status: 404 });
        }

        await prisma.user.update({ where: { id }, data: { apiKey: null } });
        return NextResponse.json({ status: true, message: "API key revoked" });
    } catch (error) {
        console.error("Admin revoke API key error:", error);
        return NextResponse.json({ status: false, message: "Failed to revoke API key", error: "Failed to revoke API key" }, { status: 500 });
    }
}
