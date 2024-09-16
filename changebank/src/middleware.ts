import { Request, Response, NextFunction } from "express";

const userDetails = "userDetails"; //Non Http-Only with user info (not trusted)

// Roles
const viewerRole = "Viewer";
const editorRole = "Editor";

export function checkRole(req: Request, res: Response, next: NextFunction) {
  // Make sure that only users with the Editor role can make changes
  const userDetailsCookie = req.cookies[userDetails];
  if (!userDetailsCookie?.id) {
    console.log("user details cookie cleared. Weird");
    return res.redirect(302, "/");
  }

  const roles = userDetailsCookie?.registrations[0].roles;
  if (roles.includes(viewerRole)) {
    res.status(403).json(
      JSON.stringify({
        error: "Unauthorized",
        message: "Request the admin to give edit access",
      })
    );
    return;
  }

  next();
}
