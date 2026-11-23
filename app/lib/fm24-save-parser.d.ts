export type FM24Player = {
  id: number; uid: number; name: string; fullName: string; age: number;
  birthDate: string; nationId: number; otherNationIds: number[]; clubId: number | null;
  club: string | null; clubFullName: string | null; contractClubId: number | null; contractClub: string | null; contractClubFullName: string | null; loanedOut: boolean; loanDestination: string | null; ca: number; pa: number;
  positions: string[]; positionRatings: number[]; attributes: Record<string, number>;
  rawAttributes: number[];
};
export type FM24Club = { id:number; uid:number; nation:number; name:string; shortName:string; offset:number };
export type FM24Save = { name:string; formatVersion:string; gameDate:string; players:FM24Player[]; clubs:FM24Club[]; warnings:string[] };
export function parseSave(bytes: Uint8Array, onProgress?: (progress:number, message:string)=>void): Promise<FM24Save>;
export const ROLES: any[];
export const ATTRIBUTES: any[];
export const POSITIONS: string[];
export function rateRole(role:any, attributes:Record<string,number>): number | null;
export const NATIONS: Record<string,string>;
