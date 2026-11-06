import { NextResponse, NextRequest } from "next/server";
import { waManager } from "@/modules/whatsapp/manager";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser, getAccessibleSessions } from "@/lib/api-auth";

export const dynamic = 'force-dynamic';

// GET: Fetch sessions (filtered by user role)
export async function GET(request: NextRequest) {
    try {
        const user = await getAuthenticatedUser(request);
        if (!user) {
            return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 401 });
        }

        // Get sessions based on user role
        const sessions = await getAccessibleSessions(user.id, user.role);
        return NextResponse.json({ status: true, message: "Sessions retrieved successfully", data: sessions });
    } catch (error) {
        console.error("Get sessions error:", error);
        return NextResponse.json({ status: false, message: "Failed to fetch sessions", error: "Failed to fetch sessions" }, { status: 500 });
    }
}

// POST: Create new session (always for the authenticated user)
export async function POST(request: NextRequest) {
    try {
        const user = await getAuthenticatedUser(request);
        if (!user) {
            return NextResponse.json({ status: false, message: "Unauthorized", error: "Unauthorized" }, { status: 401 });
        }

        const body = await request.json();
        const { name, sessionId } = body;

        if (!name) {
            return NextResponse.json({ status: false, message: "Session name is required", error: "Session name is required" }, { status: 400 });
        }

        // sessionId is used in URLs, auth-state keys and media filenames: keep it URL/file safe
        if (sessionId !== undefined && sessionId !== null &&
            (typeof sessionId !== "string" || !/^[a-zA-Z0-9_-]{3,64}$/.test(sessionId))) {
            return NextResponse.json({ status: false, message: "sessionId must be 3-64 chars: letters, numbers, '-' or '_'", error: "Invalid sessionId" }, { status: 400 });
        }

        // Per-user session quota (SUPERADMIN is never limited)
        if (user.role !== "SUPERADMIN") {
            const owner = await prisma.user.findUnique({ where: { id: user.id }, select: { maxSessions: true } });
            if (owner?.maxSessions !== null && owner?.maxSessions !== undefined) {
                const owned = await prisma.session.count({ where: { userId: user.id } });
                if (owned >= owner.maxSessions) {
                    return NextResponse.json({ status: false, message: `Session limit reached (${owner.maxSessions})`, error: "Session limit reached" }, { status: 403 });
                }
            }
        }

        if (sessionId) {
            const taken = await prisma.session.findUnique({ where: { sessionId }, select: { id: true } });
            if (taken) {
                return NextResponse.json({ status: false, message: "sessionId already in use", error: "sessionId already in use" }, { status: 409 });
            }
        }

        // Create session for the authenticated user
        const session = await waManager.createSession(user.id, name, sessionId);
        return NextResponse.json({ status: true, message: "Session created successfully", data: session });
    } catch (error: any) {
        // Unique constraint race (sessionId taken between the check and the insert)
        if (error?.code === "P2002") {
            return NextResponse.json({ status: false, message: "sessionId already in use", error: "sessionId already in use" }, { status: 409 });
        }
        console.error("Create session error:", error);
        return NextResponse.json({ status: false, message: "Failed to create session", error: "Failed to create session" }, { status: 500 });
    }
}
