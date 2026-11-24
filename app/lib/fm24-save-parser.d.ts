export type FM24Player = {
  id: number; uid: number; name: string; fullName: string; age: number;
  birthDate: string; nationId: number; otherNationIds: number[]; clubId: number | null;
  club: string | null; clubFullName: string | null; contractClubId: number | null; contractClub: string | null; contractClubFullName: string | null; loanedOut: boolean; loanDestination: string | null; ca: number; pa: number;
  positions: string[]; positionRatings: number[]; attributes: Record<string, number>;
  rawAttributes: number[]; statsGroup: number | null;
};
export type FM24Club = { id:number; uid:number; nation:number; name:string; shortName:string; offset:number };
export type FM24History = {
  managedClubId:number|null;
  clubs:{fm24ClubId:number;name:string;shortName:string;country:string|null}[];
  competitions:{uid:number;name:string;rawIds:number[]}[];
  seasons:{label:string;startDate:string;endDate:string;isCurrent:boolean}[];
  matches:{fixtureId:number;stageId:number;competitionUid:number|null;date:string;seasonStart:number;homeTeam:number;awayTeam:number;homeClubId:number|null;awayClubId:number|null;homeScore:number|null;awayScore:number|null;attendance:number|null}[];
  transfers:{personId:number;date:string;kind:number;type:string;fromClubId:number|null;toClubId:number|null;fee:number;addOns:number;originalFee:number;originalFeeWithAddOns:number}[];
  playerSeasonRecords:{personId:number;clubId:number;seasonStart:number;appearances:number;starts:number;substituteAppearances:number;minutes:number;goals:number;assists:number;playerOfMatch:number;goalsConceded:number;cleanSheets:number;yellowCards:number;redCards:number;ratedAppearances:number;ratingTotal:number;averageRating:number|null;teamIds:number[];kindBreakdown:Record<string,{appearances:number;goals:number;assists:number;minutes:number}>}[];
  trophies:{competitionUid:number;competitionKey:number;year:number;seasonStart:number;wonOn:string}[];
  warnings:string[];
};
export type FM24Save = { name:string; formatVersion:string; gameDate:string; players:FM24Player[]; clubs:FM24Club[]; teamClubMap:{teamId:number;clubId:number}[]; history:FM24History; warnings:string[] };
export function parseSave(bytes: Uint8Array, onProgress?: (progress:number, message:string)=>void, options?:{clubName?:string}): Promise<FM24Save>;
export const ROLES: any[];
export const ATTRIBUTES: any[];
export const POSITIONS: string[];
export function rateRole(role:any, attributes:Record<string,number>): number | null;
export const NATIONS: Record<string,string>;
