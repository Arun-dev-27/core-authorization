/** Version-agnostic input for the service layer (the v1 DTO satisfies it structurally). */
export interface CreateEnvironmentInput {
  code: string;
  name: string;
  is_production?: boolean;
  sort_order?: number;
}
