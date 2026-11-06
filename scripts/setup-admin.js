const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const prisma = new PrismaClient();

async function main() {
    // Optional flag: --api-key  → (re)generate and print the admin's API key
    const wantsApiKey = process.argv.includes("--api-key");
    const args = process.argv.slice(2).filter(a => a !== "--api-key");
    const email = args[0];
    const password = args[1];

    await upsertAdmin(email, password);

    if (wantsApiKey) {
        const apiKey = `wag_${crypto.randomBytes(24).toString("base64url")}`;
        await prisma.user.update({ where: { email }, data: { apiKey } });
        console.log(`API key for ${email} (previous key, if any, is now revoked):`);
        console.log(apiKey);
    }
}

async function upsertAdmin(email, password) {

    if (!email) {
        console.error("Please provide email. Usage: node scripts/setup-admin.js <email> [password] [--api-key]");
        process.exit(1);
    }

    const existingUser = await prisma.user.findUnique({
        where: { email }
    });

    if (existingUser) {
        console.log(`User ${email} found. Promoting to SUPERADMIN...`);
        await prisma.user.update({
            where: { email },
            data: { role: 'SUPERADMIN' }
        });
        console.log("User promoted successfully!");
    } else {
        if (!password) {
            console.error("Password required for new user. Usage: node scripts/setup-admin.js <email> <password> [--api-key]");
            process.exit(1);
        }

        console.log(`Creating new SUPERADMIN user ${email}...`);
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await prisma.user.create({
            data: {
                email,
                name: "Super Admin",
                password: hashedPassword,
                role: 'SUPERADMIN'
            }
        });
        console.log("Super Admin created successfully!");
    }
}

main()
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
