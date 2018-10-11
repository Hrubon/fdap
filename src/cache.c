void cache_init(struct cache *cache)
{
	cache->indices = array_new(8, sizeof(*cache->indices));
}

void cache_free(struct cache *cache)
{
	array_destroy(cache->indices);
}

void cache_flush(struct cache *cache)
{
	/* TODO */
}
