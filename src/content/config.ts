import { defineCollection, z } from "astro:content";

export const collections = {
  research: defineCollection({
    type: "content",
    schema: z.object({
      title: z.string(),
      description: z.string(),
      date: z.coerce.date(),
      tags: z.array(z.string()).default([]),
      draft: z.boolean().default(false)
    })
  })
};
